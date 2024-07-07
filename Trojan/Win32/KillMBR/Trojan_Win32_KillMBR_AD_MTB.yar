
rule Trojan_Win32_KillMBR_AD_MTB{
	meta:
		description = "Trojan:Win32/KillMBR.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 00 68 1c 00 09 00 56 ff d7 56 ff 15 90 01 01 20 00 10 68 d0 07 00 00 ff 15 90 01 01 20 00 10 ff 15 90 01 01 20 00 10 3d 90 00 } //2
		$a_01_1 = {5c 2e 5c 50 48 59 53 49 43 41 4c 44 52 49 56 45 30 } //2 \.\PHYSICALDRIVE0
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}