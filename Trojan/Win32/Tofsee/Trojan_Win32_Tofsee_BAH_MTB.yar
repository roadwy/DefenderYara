
rule Trojan_Win32_Tofsee_BAH_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.BAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c9 8a 55 ff 8a 5d fd 0a df 88 14 06 8a 55 fe 89 0d } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}