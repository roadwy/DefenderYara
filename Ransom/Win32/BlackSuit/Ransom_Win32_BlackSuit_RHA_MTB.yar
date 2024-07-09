
rule Ransom_Win32_BlackSuit_RHA_MTB{
	meta:
		description = "Ransom:Win32/BlackSuit.RHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {42 45 47 49 4e 20 52 53 41 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d 2d 2d 4d 49 49 43 49 6a 41 4e 42 67 } //2 BEGIN RSA PUBLIC KEY-----MIICIjANBg
		$a_00_1 = {72 00 65 00 61 00 64 00 6d 00 65 00 2e 00 62 00 6c 00 61 00 63 00 6b 00 73 00 75 00 69 00 74 00 2e 00 74 00 78 00 74 00 } //2 readme.blacksuit.txt
		$a_03_2 = {50 45 00 00 4c 01 05 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 02 21 0b 01 0e 22 00 c6 00 00 00 80 04 } //2
		$a_01_3 = {b8 01 00 00 00 c2 0c } //2
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}