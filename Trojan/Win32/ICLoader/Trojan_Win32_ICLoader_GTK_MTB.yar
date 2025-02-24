
rule Trojan_Win32_ICLoader_GTK_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.GTK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {0c ef 0c 00 1c ef 0c 00 30 ef 0c 00 3e ef 0c 00 4a ef 0c 00 5c ef 0c 00 30 e9 0c 00 1c e9 0c 00 0c e9 0c 00 } //5
		$a_01_1 = {48 f3 0c 00 5a f3 0c 00 6e f3 0c 00 82 f3 0c 00 9c f3 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}