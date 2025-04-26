
rule Trojan_Win32_Azorult_NC_MTB{
	meta:
		description = "Trojan:Win32/Azorult.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {51 50 50 50 50 ff 15 [0-04] 46 3b f3 90 18 e8 [0-04] 30 [0-02] 83 [0-02] 75 [0-03] 50 8d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}