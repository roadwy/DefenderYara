
rule Backdoor_Win32_Hupigon_EJ{
	meta:
		description = "Backdoor:Win32/Hupigon.EJ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 20 53 74 61 72 74 75 70 20 25 73 00 } //1 畲摮汬㈳攮數┠ⱳ匠慴瑲灵┠s
		$a_00_1 = {0d 0a 5b 25 30 32 64 2f 25 30 32 64 2f 25 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 5d 20 28 25 73 29 0d 0a } //1
		$a_03_2 = {c7 45 fc ff ff ff ff e8 ?? ?? ?? ?? 39 9d ?? ?? ff ff 75 ?? 3b f3 74 0f 56 53 ff 95 ?? ?? ff ff 50 ff 95 ?? ?? ff ff 33 c0 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}