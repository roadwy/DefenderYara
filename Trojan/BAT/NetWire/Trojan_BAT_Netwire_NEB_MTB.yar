
rule Trojan_BAT_Netwire_NEB_MTB{
	meta:
		description = "Trojan:BAT/Netwire.NEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 07 00 00 "
		
	strings :
		$a_01_0 = {4f 4f 65 32 45 50 61 64 4b 79 39 36 33 4d 36 } //3 OOe2EPadKy963M6
		$a_01_1 = {72 74 42 6f 6f 63 6c } //3 rtBoocl
		$a_01_2 = {57 68 6f 43 61 6c 6c 65 64 4d 65 } //3 WhoCalledMe
		$a_01_3 = {69 53 66 73 47 39 43 50 6e 6b } //2 iSfsG9CPnk
		$a_01_4 = {62 50 6f 68 73 52 45 63 32 50 56 5a 4a 46 4a } //2 bPohsREc2PVZJFJ
		$a_01_5 = {63 00 3a 00 5c 00 54 00 65 00 6d 00 70 00 65 00 2e 00 74 00 78 00 74 00 } //1 c:\Tempe.txt
		$a_01_6 = {61 00 45 00 4c 00 78 00 73 00 75 00 42 00 52 00 45 00 76 00 72 00 37 00 4b 00 6b 00 52 00 63 00 4d 00 53 00 32 00 66 00 69 00 52 00 6f 00 61 00 59 00 } //1 aELxsuBREvr7KkRcMS2fiRoaY
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=15
 
}