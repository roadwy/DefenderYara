
rule Trojan_Win32_Copak_FL_MTB{
	meta:
		description = "Trojan:Win32/Copak.FL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 10 81 c0 04 00 00 00 09 db 39 f8 75 ed 46 c3 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}