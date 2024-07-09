
rule Backdoor_Win32_Ripinip_H{
	meta:
		description = "Backdoor:Win32/Ripinip.H,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 84 24 04 05 00 00 41 3a 5c 00 ff 15 } //1
		$a_03_1 = {81 7e 04 01 14 00 00 75 1e 8b 56 08 6a 00 8d 46 0c 50 52 55 57 ff 15 ?? ?? ?? ?? 56 8b cb e8 ?? ?? ff ff 85 c0 75 d9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}