
rule Trojan_Win32_SuspLolbinLaunch_D_credwiz{
	meta:
		description = "Trojan:Win32/SuspLolbinLaunch.D!credwiz,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_00_0 = {63 00 72 00 65 00 64 00 77 00 69 00 7a 00 2e 00 65 00 78 00 65 00 } //5 credwiz.exe
	condition:
		((#a_00_0  & 1)*5) >=5
 
}