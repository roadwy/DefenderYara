
rule Trojan_AndroidOS_Clicker_MF_MTB{
	meta:
		description = "Trojan:AndroidOS/Clicker.MF!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 7a 79 7a 79 2e 67 6f 67 6f } //2 com.zyzy.gogo
		$a_00_1 = {26 61 63 74 3d 61 64 76 } //1 &act=adv
		$a_00_2 = {61 48 52 30 63 44 6f 76 4c 32 46 6b 63 32 4e 73 64 57 4a 77 59 58 4a 30 62 6d 56 79 63 79 35 79 64 53 39 77 4c 6e 42 6f 63 41 3d 3d } //1 aHR0cDovL2Fkc2NsdWJwYXJ0bmVycy5ydS9wLnBocA==
		$a_00_3 = {43 48 45 43 4b 20 49 4e 45 54 20 32 20 45 4e 44 } //1 CHECK INET 2 END
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}