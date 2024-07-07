
rule Trojan_BAT_Wiper_E{
	meta:
		description = "Trojan:BAT/Wiper.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 54 65 73 74 73 5c 43 6f 6e 73 6f 6c 65 5c 50 72 6f 67 65 63 74 52 65 76 65 6e 67 65 5c 70 75 72 65 5f 67 6f 6f 66 5c } //1 \Tests\Console\ProgectRevenge\pure_goof\
		$a_01_1 = {70 75 72 65 5f 67 6f 6f 66 2e 65 78 65 } //1 pure_goof.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}