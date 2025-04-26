
rule Trojan_Win32_Zenpak_SCVP_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.SCVP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 77 63 64 74 68 6f 64 73 48 6c 75 } //3 AwcdthodsHlu
	condition:
		((#a_01_0  & 1)*3) >=3
 
}