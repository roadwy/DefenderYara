
rule TrojanSpy_Win32_SocStealer_D_ibt{
	meta:
		description = "TrojanSpy:Win32/SocStealer.D!ibt,SIGNATURE_TYPE_PEHSTR,05 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {62 75 73 69 6e 65 73 73 5f 69 64 } //1 business_id
		$a_01_1 = {63 72 65 64 69 74 5f 63 61 72 64 73 } //1 credit_cards
		$a_01_2 = {46 72 69 65 6e 64 43 6f 75 6e 74 } //1 FriendCount
		$a_01_3 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 66 61 63 65 62 6f 6f 6b 2e 63 6f 6d 2f } //1 https://www.facebook.com/
		$a_01_4 = {3c 73 63 72 69 70 74 3e 62 69 67 50 69 70 65 2e 62 65 66 6f 72 65 50 61 67 65 6c 65 74 41 72 72 69 76 65 } //1 <script>bigPipe.beforePageletArrive
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}