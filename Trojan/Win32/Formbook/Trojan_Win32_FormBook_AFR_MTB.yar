
rule Trojan_Win32_FormBook_AFR_MTB{
	meta:
		description = "Trojan:Win32/FormBook.AFR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 db 89 45 a8 33 ff 8b 0d 90 01 04 0f af cb b8 7f e0 07 7e f7 e9 c1 fa 05 8d 73 01 8b c2 8b ce 0f af 0d 90 01 04 c1 e8 1f 03 c2 89 45 ec b8 7f e0 07 7e f7 e9 c1 fa 05 8b ca c1 e9 1f 03 ca 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}