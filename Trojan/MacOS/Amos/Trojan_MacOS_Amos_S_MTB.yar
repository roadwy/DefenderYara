
rule Trojan_MacOS_Amos_S_MTB{
	meta:
		description = "Trojan:MacOS/Amos.S!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {e8 e6 19 02 00 89 c1 44 29 f9 31 db 48 83 f8 01 19 db 08 cb 0f be 75 d6 4c 89 ff } //2
		$a_01_1 = {48 8b 05 9a 21 02 00 48 8b 00 48 3b 45 d0 75 31 31 c0 48 83 c4 78 5b 41 5c 41 5d 41 5e 41 5f 5d } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}