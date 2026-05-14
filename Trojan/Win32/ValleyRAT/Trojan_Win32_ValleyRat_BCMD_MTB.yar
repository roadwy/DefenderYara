
rule Trojan_Win32_ValleyRat_BCMD_MTB{
	meta:
		description = "Trojan:Win32/ValleyRat.BCMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 02 99 be ?? ?? ?? ?? f7 fe 83 c2 ?? 8b 45 ?? 0f be 0c 01 33 ca 8b 55 ?? 8b 42 ?? 8b 55 ?? 88 0c 10 eb } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}