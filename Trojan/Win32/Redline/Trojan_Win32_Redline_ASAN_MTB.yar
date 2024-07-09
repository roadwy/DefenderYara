
rule Trojan_Win32_Redline_ASAN_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {fe ff 50 e8 ?? ?? fe ff 80 34 1f } //1
		$a_03_1 = {fe ff 50 e8 ?? ?? fe ff 80 04 1f ?? 83 c4 30 47 3b fe 0f 82 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}