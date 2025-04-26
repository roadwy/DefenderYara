
rule Trojan_Win32_Shellcode_GPA_MTB{
	meta:
		description = "Trojan:Win32/Shellcode.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 74 26 00 89 c1 83 e1 1f 0f b6 0c 0c 30 0c 02 83 c0 01 39 c3 75 ed } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}