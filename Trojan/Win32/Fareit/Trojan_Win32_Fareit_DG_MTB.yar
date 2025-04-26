
rule Trojan_Win32_Fareit_DG_MTB{
	meta:
		description = "Trojan:Win32/Fareit.DG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {fb 6a 09 66 81 ff 9e 77 66 85 d2 81 fb af 70 3b 39 66 3d 3f 03 85 d2 eb 03 00 00 00 ff e0 66 81 fb 84 77 66 85 d2 85 d2 0f 6e da 81 fb 5e 9a 55 f4 31 f1 66 85 d2 eb 0c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}