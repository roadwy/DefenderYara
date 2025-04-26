
rule Trojan_BAT_PureLogStealer_KAE_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.KAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_80_0 = {2f 2f 6a 6f 66 69 6c 65 73 6a 6f 2e 63 6f 6d } ////jofilesjo.com  2
		$a_80_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //DownloadData  2
		$a_80_2 = {52 65 76 65 72 73 65 } //Reverse  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1) >=5
 
}