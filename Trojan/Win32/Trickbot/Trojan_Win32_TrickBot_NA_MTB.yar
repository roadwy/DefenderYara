
rule Trojan_Win32_TrickBot_NA_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {c6 00 40 c6 40 01 6b c6 40 02 72 c6 40 03 2d c6 40 04 4a c6 40 05 02 } //2
		$a_01_1 = {89 e6 8d 48 ff 0f af c8 89 c8 83 f0 fe 85 c8 } //1
		$a_81_2 = {40 57 40 4b 72 61 73 49 6f 64 57 } //1 @W@KrasIodW
		$a_81_3 = {4b 72 61 73 49 6f 64 57 } //1 KrasIodW
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=5
 
}