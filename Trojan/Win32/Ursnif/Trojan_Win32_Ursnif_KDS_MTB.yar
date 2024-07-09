
rule Trojan_Win32_Ursnif_KDS_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.KDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_02_0 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? ?? ?? c1 e8 10 25 ff 7f 00 00 c3 90 09 05 00 a1 } //2
		$a_00_1 = {30 84 37 00 fe ff ff } //1
		$a_02_2 = {69 c0 fd 43 03 00 8d 8d f8 f7 ff ff 51 05 c3 9e 26 00 90 09 05 00 a1 } //2
		$a_00_3 = {30 04 3e 46 } //1 а䘾
		$a_02_4 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? ?? ?? 8d 45 f8 50 56 ?? ?? ?? ?? ?? ?? a0 ?? ?? ?? ?? 30 04 1f 90 09 05 00 a1 } //3
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*1+(#a_02_2  & 1)*2+(#a_00_3  & 1)*1+(#a_02_4  & 1)*3) >=3
 
}