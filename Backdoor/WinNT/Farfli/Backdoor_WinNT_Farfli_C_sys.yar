
rule Backdoor_WinNT_Farfli_C_sys{
	meta:
		description = "Backdoor:WinNT/Farfli.C!sys,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {ff 75 0c ff 75 08 e8 90 01 01 fc ff ff 84 c0 58 8b e5 5d 74 11 aa bb cc dd ee ff aa aa aa aa ea bb bb bb bb 08 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}