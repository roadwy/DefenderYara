
rule Trojan_BAT_Exnet_SWA_MTB{
	meta:
		description = "Trojan:BAT/Exnet.SWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {23 45 74 68 65 72 53 68 69 65 6c 64 } //2 #EtherShield
		$a_01_1 = {43 61 70 74 75 72 65 53 63 72 65 65 6e } //1 CaptureScreen
		$a_01_2 = {41 6e 74 69 44 6c 6c 49 6e 6a 65 63 74 69 6f 6e } //1 AntiDllInjection
		$a_01_3 = {48 6f 6f 6b 73 44 65 74 65 63 74 69 6f 6e } //1 HooksDetection
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}