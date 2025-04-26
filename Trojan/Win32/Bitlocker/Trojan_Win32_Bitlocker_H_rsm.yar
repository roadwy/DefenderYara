
rule Trojan_Win32_Bitlocker_H_rsm{
	meta:
		description = "Trojan:Win32/Bitlocker.H!rsm,SIGNATURE_TYPE_CMDHSTR_EXT,64 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {64 00 65 00 6c 00 20 00 [0-30] 2a 00 2e 00 42 00 45 00 4b 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}