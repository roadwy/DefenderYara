
rule VirTool_Win64_Smbtkovr_A{
	meta:
		description = "VirTool:Win64/Smbtkovr.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 bb 32 a2 df 2d 99 2b 00 00 48 3b c3 ?? ?? 48 83 65 10 00 ?? ?? ?? ?? ff ?? ?? ?? ?? ?? 48 8b 45 10 48 89 45 f0 ff ?? ?? ?? ?? ?? 8b c0 48 31 45 f0 ff ?? ?? ?? ?? ?? 8b c0 ?? ?? ?? ?? 48 31 45 f0 ff ?? ?? ?? ?? ?? 8b 45 18 ?? ?? ?? ?? 48 c1 e0 20 } //1
		$a_01_1 = {69 6d 70 61 63 6b 65 74 2e 73 6d 62 63 6f 6e 6e 65 63 74 69 6f 6e 29 03 72 06 00 00 00 69 62 76 } //1
		$a_01_2 = {65 6d 61 69 6c 2e 5f 65 6e 63 6f 64 65 64 5f 77 6f 72 64 73 } //1 email._encoded_words
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}