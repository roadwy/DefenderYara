
rule Trojan_Win32_Farfli_U_MTB{
	meta:
		description = "Trojan:Win32/Farfli.U!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {6d 4d c1 50 ?? ?? c0 bf ?? ?? ?? ?? ?? 24 ?? fd ad 22 ff 69 a6 ?? ?? ?? ?? ?? ?? ?? ?? 3b c4 ce f8 58 d4 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}