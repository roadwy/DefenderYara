
rule Trojan_Win32_Pipesatues_A_{
	meta:
		description = "Trojan:Win32/Pipesatues.A!!Pipesatues.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 f0 b5 a2 56 ff d5 ff 64 24 10 e8 53 ff ff ff 5c 5c 2e 5c 70 69 70 65 5c 73 74 61 74 75 73 5f 38 30 38 30 00 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}