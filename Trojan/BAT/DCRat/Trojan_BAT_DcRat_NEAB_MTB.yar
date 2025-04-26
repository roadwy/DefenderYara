
rule Trojan_BAT_DcRat_NEAB_MTB{
	meta:
		description = "Trojan:BAT/DcRat.NEAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {28 38 00 00 0a 25 28 0a 33 00 06 28 39 00 00 0a 73 3a 00 00 0a 28 3b 00 00 0a 26 2a } //5
		$a_01_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 74 00 72 00 61 00 6e 00 73 00 66 00 65 00 72 00 2e 00 73 00 68 00 2f 00 67 00 65 00 74 00 } //2 https://transfer.sh/get
		$a_01_2 = {45 00 78 00 65 00 63 00 75 00 74 00 65 00 42 00 79 00 74 00 65 00 73 00 2e 00 74 00 78 00 74 00 } //2 ExecuteBytes.txt
		$a_01_3 = {6e 00 61 00 7a 00 61 00 4d 00 57 00 34 00 38 00 37 00 2e 00 65 00 78 00 65 00 } //2 nazaMW487.exe
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=11
 
}