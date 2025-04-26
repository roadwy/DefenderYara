
rule Trojan_Win32_Shellcode_EARU_MTB{
	meta:
		description = "Trojan:Win32/Shellcode.EARU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b d6 c1 ea 05 89 55 fc 8b 45 e4 01 45 fc 8b 45 f4 c1 e6 04 03 75 dc 8d 0c 03 33 f1 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}