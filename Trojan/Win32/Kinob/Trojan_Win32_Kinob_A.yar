
rule Trojan_Win32_Kinob_A{
	meta:
		description = "Trojan:Win32/Kinob.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 18 45 8b c5 83 e0 03 8a 5c 04 10 32 1c 29 0f 85 60 ff ff ff } //1
		$a_03_1 = {8b 46 08 03 c1 6a 00 50 e8 ?? ?? ?? ?? 83 c4 0c 8d 4c ?? ?? 51 68 ?? ?? ?? ?? c7 44 ?? ?? 1a 00 00 00 e8 } //1
		$a_01_2 = {4f 69 6e 6b 4f 69 6e 6b 2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //1 楏歮楏歮搮汬䐀汬慃啮汮慯乤睯
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}