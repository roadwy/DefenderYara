
rule Trojan_Win32_Injeber_C_bit{
	meta:
		description = "Trojan:Win32/Injeber.C!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {69 20 61 6d 20 67 6f 6e 6e 61 20 66 75 63 6b 20 79 6f 75 72 20 74 69 74 73 20 25 73 } //1 i am gonna fuck your tits %s
		$a_01_1 = {70 61 79 6c 6f 61 64 20 69 73 20 69 74 } //1 payload is it
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}