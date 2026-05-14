
rule Trojan_Win32_PhantomStealer_RV_MTB{
	meta:
		description = "Trojan:Win32/PhantomStealer.RV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {6c 65 67 69 74 69 6d 61 74 69 7a 65 73 20 73 74 61 64 69 6f 6d 65 74 65 72 } //1 legitimatizes stadiometer
		$a_81_1 = {74 72 69 6c 61 62 65 20 66 6f 72 65 74 61 67 65 6e 64 65 72 20 70 72 6f 6d 61 67 69 73 74 72 61 74 65 } //1 trilabe foretagender promagistrate
		$a_81_2 = {61 62 65 72 72 61 74 69 76 65 } //1 aberrative
		$a_81_3 = {66 72 65 6d 61 76 6c 65 2e 65 78 65 } //1 fremavle.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}