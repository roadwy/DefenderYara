
rule Trojan_Win32_Bitlocker_F_rsm{
	meta:
		description = "Trojan:Win32/Bitlocker.F!rsm,SIGNATURE_TYPE_CMDHSTR_EXT,64 00 0a 00 01 00 00 "
		
	strings :
		$a_00_0 = {2d 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2d 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 66 00 65 00 61 00 74 00 75 00 72 00 65 00 20 00 62 00 69 00 74 00 6c 00 6f 00 63 00 6b 00 65 00 72 00 20 00 2d 00 72 00 65 00 73 00 74 00 61 00 72 00 74 00 } //10 -command install-windowsfeature bitlocker -restart
	condition:
		((#a_00_0  & 1)*10) >=10
 
}