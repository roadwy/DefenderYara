
rule Trojan_Win32_Eggnog_MA_MTB{
	meta:
		description = "Trojan:Win32/Eggnog.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c3 60 61 6a 0a 5f 99 f7 ff 80 c2 30 29 c0 8a c1 88 14 06 8b c3 bb 0a 00 00 00 99 f7 fb 50 5b 49 09 db 75 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}