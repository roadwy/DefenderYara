
rule Trojan_Win32_Tavsurv_A_dha{
	meta:
		description = "Trojan:Win32/Tavsurv.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {30 07 83 c7 01 83 c5 01 3b 6c 24 28 7c bb } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}