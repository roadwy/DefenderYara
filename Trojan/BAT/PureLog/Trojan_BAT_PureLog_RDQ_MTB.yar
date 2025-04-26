
rule Trojan_BAT_PureLog_RDQ_MTB{
	meta:
		description = "Trojan:BAT/PureLog.RDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {30 39 35 61 35 63 38 38 2d 64 33 36 35 2d 34 63 35 34 2d 39 61 66 66 2d 64 31 36 38 63 62 32 38 65 64 30 30 } //2 095a5c88-d365-4c54-9aff-d168cb28ed00
		$a_01_1 = {6d 75 73 69 63 53 44 70 6c 61 79 65 72 } //1 musicSDplayer
		$a_01_2 = {53 70 65 63 63 79 20 49 6e 73 74 61 6c 6c 65 72 } //1 Speccy Installer
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}