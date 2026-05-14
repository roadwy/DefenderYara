
rule Trojan_Win32_EmailWorm_PGEW_MTB{
	meta:
		description = "Trojan:Win32/EmailWorm.PGEW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {60 00 00 c0 2e 66 6c 68 00 00 00 00 00 10 00 00 00 30 03 00 00 02 00 00 00 20 01 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 60 72 70 55 72 45 72 62 64 4e 19 00 00 00 40 03 00 00 1a 00 00 00 22 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 70 45 6e 58 44 61 79 75 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}