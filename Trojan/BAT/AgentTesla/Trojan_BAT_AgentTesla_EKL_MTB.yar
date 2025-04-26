
rule Trojan_BAT_AgentTesla_EKL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {1d 09 1d 09 1d 09 1d 09 1d 09 45 00 1d 09 1d 09 1d 09 52 00 1d 09 44 00 69 00 45 00 1d 09 1d 09 1d 09 1d 09 4f 00 49 00 55 00 1d 09 1d 09 1d 09 1d 09 } //1 झझझझझEझझझRझDiEझझझझOIUझझझझ
		$a_01_1 = {47 00 79 00 77 00 78 00 4b 00 77 00 45 00 57 00 43 00 77 00 4e 00 76 00 38 00 67 00 1d 09 1d 09 42 00 69 00 77 00 67 00 42 00 6d 00 2f 00 79 00 } //1 GywxKwEWCwNv8gझझBiwgBm/y
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}