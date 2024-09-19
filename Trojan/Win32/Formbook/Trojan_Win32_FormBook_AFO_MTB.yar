
rule Trojan_Win32_FormBook_AFO_MTB{
	meta:
		description = "Trojan:Win32/FormBook.AFO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {59 59 8d 85 7c ea ff ff 50 8d 85 5c eb ff ff 50 8d 85 a0 eb ff ff 50 8d 85 54 eb ff ff 50 8d 85 4c fc ff ff 50 ff 15 } //1
		$a_03_1 = {6a 00 6a 00 6a 00 8d 85 74 fd ff ff 50 ff 15 ?? ?? ?? ?? 85 c0 74 3b a1 ?? ?? ?? ?? 0f af 45 c8 03 45 cc a3 ?? ?? ?? ?? 8b 45 98 48 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}