import ai_tester_core.attack_generation as ag


def test_automated_prompt_fuzzer_yields_seed():
    seed = "attack"
    fuzzed = list(ag.automated_prompt_fuzzer(seed))
    assert fuzzed[0] == seed


def test_adversarial_prompt_generator_returns_seed():
    seed = "prompt"
    prompts = ag.adversarial_prompt_generator(seed)
    assert prompts == [seed]


def test_multi_turn_attack_creator_structure():
    seed = "start"
    sequences = ag.multi_turn_attack_creator(seed)
    assert sequences == [[seed]]


def test_encoding_bypass_generator_identity():
    text = "hello"
    variants = ag.encoding_bypass_generator(text)
    assert variants == [text]


def test_social_engineering_prompter_basic():
    topic = "help"
    prompts = ag.social_engineering_prompter(topic)
    assert any(topic in p for p in prompts)
