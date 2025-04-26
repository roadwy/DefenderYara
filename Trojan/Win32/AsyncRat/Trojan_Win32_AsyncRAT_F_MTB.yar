
rule Trojan_Win32_AsyncRAT_F_MTB{
	meta:
		description = "Trojan:Win32/AsyncRAT.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {6c ff 6c 70 ff fc 90 6c 68 ff 6c 74 ff fc 90 fb 11 6c 6c ff 6c 70 ff fc a0 6c 68 ff f5 01 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}