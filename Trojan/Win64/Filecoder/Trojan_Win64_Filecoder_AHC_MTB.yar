
rule Trojan_Win64_Filecoder_AHC_MTB{
	meta:
		description = "Trojan:Win64/Filecoder.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,5a 00 5a 00 03 00 00 "
		
	strings :
		$a_01_0 = {5b 2b 5d 20 44 65 63 72 79 70 74 65 64 20 3d 3e } //20 [+] Decrypted =>
		$a_01_1 = {72 61 6e 73 6f 6d 5f 6e 6f 74 65 5f 65 78 65 63 2e 65 78 65 } //30 ransom_note_exec.exe
		$a_03_2 = {41 32 54 05 ?? 89 d1 f6 d9 08 d1 f6 d1 c0 e9 ?? e8 ?? ?? ?? ?? 20 c3 4c 89 f0 4c 39 f6 75 } //40
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*30+(#a_03_2  & 1)*40) >=90
 
}