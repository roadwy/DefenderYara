
rule Trojan_Win32_Vundo_IJ{
	meta:
		description = "Trojan:Win32/Vundo.IJ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {46 56 67 63 0d 20 78 11 c7 f5 e2 67 7c 08 ac 6a ef 9d 7c 25 09 bf 49 c7 66 b6 03 e2 f8 8e 6a ba } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}