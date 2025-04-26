
rule Trojan_Win32_Ursnif_SP_MSR{
	meta:
		description = "Trojan:Win32/Ursnif.SP!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {6c 00 69 00 74 00 74 00 6c 00 65 00 75 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 70 00 72 00 65 00 76 00 69 00 6f 00 75 00 73 00 6c 00 79 00 } //1 littleuSettingspreviously
		$a_01_1 = {64 00 66 00 6f 00 72 00 65 00 6e 00 73 00 69 00 63 00 66 00 72 00 6f 00 6d 00 } //1 dforensicfrom
		$a_01_2 = {76 00 62 00 61 00 72 00 42 00 73 00 61 00 6e 00 64 00 62 00 6f 00 78 00 6f 00 70 00 74 00 69 00 6f 00 6e 00 61 00 6c 00 64 00 65 00 65 00 6d 00 65 00 64 00 } //1 vbarBsandboxoptionaldeemed
		$a_01_3 = {49 6b 65 78 70 6c 6f 69 74 73 61 66 74 65 72 6b 51 } //1 IkexploitsafterkQ
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}