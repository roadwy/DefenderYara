
rule Trojan_Win32_Upatre_AHB_MTB{
	meta:
		description = "Trojan:Win32/Upatre.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 07 8a 26 02 25 ?? ?? ?? 00 32 c4 eb ?? 00 00 00 88 07 3b f2 74 ?? 46 47 49 75 } //10
		$a_01_1 = {23 ff 6a 07 09 52 6d 30 7a 05 50 00 b4 bc 63 7c 00 00 04 1c 00 72 0a d4 00 00 41 2c 0e 3c 02 00 23 44 44 } //5
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}