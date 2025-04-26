
rule Trojan_Win32_Injector_BH{
	meta:
		description = "Trojan:Win32/Injector.BH,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {df e0 f6 c4 ?? 75 ed (d0|d1) d8 dd 05 c0 30 40 00 e8 a3 08 00 00 33 f6 8a d8 89 75 fc bf 20 30 40 00 db 45 fc dc 1d c0 25 40 00 df e0 f6 c4 41 75 12 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}