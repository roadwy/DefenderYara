
rule Trojan_BAT_PulsarRat_GDB_MTB{
	meta:
		description = "Trojan:BAT/PulsarRat.GDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {50 75 6c 73 61 72 2e 43 6f 6d 6d 6f 6e 2e 64 6c 6c } //1 Pulsar.Common.dll
		$a_81_1 = {4d 65 73 73 61 67 65 73 2e 41 64 6d 69 6e 69 73 74 72 61 74 69 6f 6e 2e 52 65 76 65 72 73 65 50 72 6f 78 79 } //1 Messages.Administration.ReverseProxy
		$a_81_2 = {55 73 65 72 53 75 70 70 6f 72 74 2e 52 65 6d 6f 74 65 43 68 61 74 } //1 UserSupport.RemoteChat
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}