
rule Trojan_BAT_Bladabindi_MBFU_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.MBFU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {54 56 71 51 3d 3d 4d 3d 3d 3d 3d 45 3d 3d 3d 3d 2f 2f 38 3d 3d 4c 67 3d 3d 3d 3d 3d 3d 3d 3d 3d 51 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 3d 67 3d 3d 3d 3d 3d 34 66 75 67 34 3d 74 3d 6e 4e 49 } //1 TVqQ==M====E====//8==Lg=========Q===============================================g=====4fug4=t=nNI
	condition:
		((#a_01_0  & 1)*1) >=1
 
}