
rule Trojan_Win32_ValleyRat_BMD_MTB{
	meta:
		description = "Trojan:Win32/ValleyRat.BMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {74 10 3b f9 7e ?? 8b 46 08 80 34 08 ?? 41 3b cf 7c } //2
		$a_01_1 = {25 00 73 00 5c 00 73 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 } //2 %s\shell\open\command
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}