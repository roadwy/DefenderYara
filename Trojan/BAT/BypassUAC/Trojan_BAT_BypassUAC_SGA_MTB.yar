
rule Trojan_BAT_BypassUAC_SGA_MTB{
	meta:
		description = "Trojan:BAT/BypassUAC.SGA!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {5c 00 44 00 6f 00 66 00 75 00 73 00 32 00 5c 00 4d 00 6f 00 64 00 75 00 6c 00 65 00 5f 00 41 00 6e 00 6b 00 61 00 6d 00 61 00 5f 00 43 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 64 00 61 00 74 00 } //2 \Dofus2\Module_Ankama_Connection.dat
	condition:
		((#a_01_0  & 1)*2) >=2
 
}