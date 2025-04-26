
rule Trojan_BAT_BitRAT_MBIB_MTB{
	meta:
		description = "Trojan:BAT/BitRAT.MBIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {0a 07 09 07 8e 69 5d 91 61 d2 9c 08 18 58 0c 08 03 6f } //10
		$a_01_1 = {73 00 4c 00 6f 00 67 00 2e 00 65 00 78 00 65 00 } //1 sLog.exe
		$a_01_2 = {31 00 2e 00 65 00 78 00 65 00 } //1 1.exe
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=11
 
}