
rule Trojan_Win32_Skintrim_H{
	meta:
		description = "Trojan:Win32/Skintrim.H,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_12_0 = {ff ff 53 c6 85 90 01 01 ff ff ff 74 c6 85 90 01 01 ff ff ff 61 c6 85 90 01 01 ff ff ff 72 c6 85 90 01 01 ff ff ff 74 c6 85 90 01 01 ff ff ff 4d c6 85 90 01 01 ff ff ff 43 90 00 01 } //1
		$a_ff_1 = {31 c6 85 90 01 02 ff ff 36 c6 85 90 01 02 ff ff 36 c6 } //27904
	condition:
		((#a_12_0  & 1)*1+(#a_ff_1  & 1)*27904) >=1
 
}