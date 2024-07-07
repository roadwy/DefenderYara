
rule Trojan_Win32_Tibs_FC{
	meta:
		description = "Trojan:Win32/Tibs.FC,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 ed 4d 83 ed 90 01 01 89 ea 08 d2 75 03 83 c0 02 89 e9 09 cd 75 ee bf 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}