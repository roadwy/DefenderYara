
rule Trojan_BAT_Stealer_SGD_MTB{
	meta:
		description = "Trojan:BAT/Stealer.SGD!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {54 65 6c 65 53 74 65 61 6c 2e 52 65 6e 63 69 2e 53 73 68 4e 65 74 2e 64 6c 6c } //1 TeleSteal.Renci.SshNet.dll
		$a_01_1 = {5c 54 65 6c 65 53 74 65 61 6c 2e 70 64 62 } //1 \TeleSteal.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}