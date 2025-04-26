
rule Trojan_Win32_Fakevisec{
	meta:
		description = "Trojan:Win32/Fakevisec,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 76 5f 66 61 6b 65 2e 73 63 61 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 av_fake.scan.resources
		$a_00_1 = {59 00 6f 00 75 00 20 00 6e 00 65 00 65 00 64 00 20 00 74 00 6f 00 20 00 72 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 20 00 56 00 69 00 73 00 74 00 61 00 20 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00 32 00 30 00 31 00 30 00 } //1 You need to register Vista Security 2010
		$a_00_2 = {59 00 6f 00 75 00 20 00 68 00 61 00 76 00 65 00 20 00 31 00 31 00 20 00 76 00 69 00 72 00 75 00 73 00 65 00 73 00 21 00 } //1 You have 11 viruses!
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}